// Copyright 2023-2026 Ant Investor Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package events contains asynchronous event handlers for the default
// authentication app. Events are emitted by HTTP handlers (e.g. social
// login) and consumed off the main request path so that expensive side
// effects (avatar downloads, uploads, profile writes) do not delay the
// login response.
package events

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"buf.build/gen/go/antinvestor/files/connectrpc/go/files/v1/filesv1connect"
	filesv1 "buf.build/gen/go/antinvestor/files/protocolbuffers/go/files/v1"
	"buf.build/gen/go/antinvestor/profile/connectrpc/go/profile/v1/profilev1connect"
	profilev1 "buf.build/gen/go/antinvestor/profile/protocolbuffers/go/profile/v1"
	"connectrpc.com/connect"
	fevents "github.com/pitabwire/frame/events"
	"github.com/pitabwire/util"
	"google.golang.org/protobuf/types/known/structpb"
)

// EventKeyProfileAvatarSync identifies the avatar-sync event. A producer
// emits it after a successful external-IdP login when the provider supplied
// a picture URL; the consumer downloads, uploads to the files service, and
// writes the resulting media id onto the profile's Properties map.
const EventKeyProfileAvatarSync = "auth.profile.avatar.sync"

// Property keys on the profile's Properties map. Kept in sync with
// handlers.KeyProfileAvatarFileID and handlers.KeyProfileAvatarURL; this
// package cannot import the handlers package without a cycle.
const (
	profilePropAvatarFileID = "au_avatar_file_id"
	profilePropAvatarURL    = "au_avatar_url"
)

// Hard caps on the avatar download to bound work done by the consumer.
const (
	avatarMaxBytes      = 5 * 1024 * 1024 // 5 MiB — generous for a profile picture
	avatarFetchTimeout  = 10 * time.Second
	avatarUploadTimeout = 30 * time.Second
)

// allowedAvatarContentTypes caps what we accept from external IdPs to
// well-known image formats. Anything else is dropped without ingesting.
var allowedAvatarContentTypes = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/webp": ".webp",
	"image/gif":  ".gif",
}

// ProfileAvatarSyncPayload is the wire payload for EventKeyProfileAvatarSync.
type ProfileAvatarSyncPayload struct {
	ProfileID string `json:"profile_id"`
	SourceURL string `json:"source_url"`
	Provider  string `json:"provider"`
}

// ProfileAvatarSyncEvent consumes EventKeyProfileAvatarSync. It is idempotent:
// if the profile already carries an avatar_file_id property, the event is a
// no-op so retries are safe.
type ProfileAvatarSyncEvent struct {
	profileCli profilev1connect.ProfileServiceClient
	filesCli   filesv1connect.FilesServiceClient
	httpCli    *http.Client
}

// NewProfileAvatarSyncEventHandler constructs the consumer.
func NewProfileAvatarSyncEventHandler(
	profileCli profilev1connect.ProfileServiceClient,
	filesCli filesv1connect.FilesServiceClient,
) fevents.EventI {
	return &ProfileAvatarSyncEvent{
		profileCli: profileCli,
		filesCli:   filesCli,
		httpCli:    &http.Client{Timeout: avatarFetchTimeout},
	}
}

// Name implements fevents.EventI.
func (e *ProfileAvatarSyncEvent) Name() string { return EventKeyProfileAvatarSync }

// PayloadType implements fevents.EventI.
func (e *ProfileAvatarSyncEvent) PayloadType() any { return &ProfileAvatarSyncPayload{} }

// Validate implements fevents.EventI.
func (e *ProfileAvatarSyncEvent) Validate(_ context.Context, payload any) error {
	p, ok := payload.(*ProfileAvatarSyncPayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *ProfileAvatarSyncPayload got %T", payload)
	}
	if p.ProfileID == "" || p.SourceURL == "" {
		return errors.New("payload requires profile_id and source_url")
	}
	return nil
}

// Execute implements fevents.EventI. It is designed to be retry-safe and
// logs-and-swallows recoverable errors on the download/upload path so the
// event doesn't wedge in the queue behind a single broken provider URL.
func (e *ProfileAvatarSyncEvent) Execute(ctx context.Context, payload any) error {
	p, ok := payload.(*ProfileAvatarSyncPayload)
	if !ok {
		return fmt.Errorf("invalid payload type, expected *ProfileAvatarSyncPayload got %T", payload)
	}
	log := util.Log(ctx).WithFields(map[string]any{
		"profile_id": p.ProfileID,
		"provider":   p.Provider,
	})

	// Fetch current profile to check for an existing avatar.
	getResp, err := e.profileCli.GetById(ctx, connect.NewRequest(&profilev1.GetByIdRequest{Id: p.ProfileID}))
	if err != nil {
		log.WithError(err).Warn("avatar sync: profile lookup failed")
		return fmt.Errorf("get profile: %w", err)
	}
	profile := getResp.Msg.GetData()
	if profile == nil {
		return fmt.Errorf("profile %s not found", p.ProfileID)
	}

	existing := profileProperties(profile)
	if v, ok := existing[profilePropAvatarFileID]; ok && v != "" {
		log.Debug("avatar sync: skipped — profile already has an avatar")
		return nil
	}

	body, contentType, fetchErr := e.fetchAvatarBytes(ctx, p.SourceURL)
	if fetchErr != nil {
		log.WithError(fetchErr).Warn("avatar sync: fetch failed — skipping")
		return nil // don't retry transient provider-side failures
	}

	mediaID, uploadErr := e.uploadAvatar(ctx, p.ProfileID, p.Provider, contentType, body)
	if uploadErr != nil {
		log.WithError(uploadErr).Error("avatar sync: upload to files service failed")
		return uploadErr // let the event retry
	}

	if updateErr := e.setProfileAvatar(ctx, p.ProfileID, existing, mediaID, p.SourceURL); updateErr != nil {
		log.WithError(updateErr).Error("avatar sync: profile update failed")
		return updateErr
	}

	log.WithField("media_id", mediaID).Info("avatar sync: profile avatar populated")
	return nil
}

// fetchAvatarBytes downloads the avatar, enforces the Content-Type allowlist
// and byte cap, and returns the raw bytes plus the canonical Content-Type.
func (e *ProfileAvatarSyncEvent) fetchAvatarBytes(ctx context.Context, rawURL string) ([]byte, string, error) {
	if !strings.HasPrefix(rawURL, "https://") && !strings.HasPrefix(rawURL, "http://") {
		return nil, "", fmt.Errorf("unsupported scheme")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := e.httpCli.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer util.CloseAndLogOnError(ctx, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("avatar fetch returned HTTP %d", resp.StatusCode)
	}

	contentType := strings.ToLower(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0])
	contentType = strings.TrimSpace(contentType)
	if _, ok := allowedAvatarContentTypes[contentType]; !ok {
		return nil, "", fmt.Errorf("unsupported content type %q", contentType)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, avatarMaxBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read avatar body: %w", err)
	}
	if len(body) > avatarMaxBytes {
		return nil, "", fmt.Errorf("avatar exceeds %d bytes", avatarMaxBytes)
	}
	return body, contentType, nil
}

// uploadAvatar streams the bytes to the files service and returns the media id.
func (e *ProfileAvatarSyncEvent) uploadAvatar(
	ctx context.Context, profileID, provider, contentType string, body []byte,
) (string, error) {
	uploadCtx, cancel := context.WithTimeout(ctx, avatarUploadTimeout)
	defer cancel()

	stream := e.filesCli.UploadContent(uploadCtx)
	ext := allowedAvatarContentTypes[contentType]
	filename := "avatar-" + sanitiseProvider(provider) + "-" + profileID + ext

	meta := &filesv1.UploadContentRequest_Metadata{
		Metadata: &filesv1.UploadMetadata{
			ContentType: contentType,
			Filename:    filename,
		},
	}
	if err := stream.Send(&filesv1.UploadContentRequest{Data: meta}); err != nil {
		return "", fmt.Errorf("send metadata: %w", err)
	}
	if err := stream.Send(&filesv1.UploadContentRequest{Data: &filesv1.UploadContentRequest_Chunk{Chunk: body}}); err != nil {
		return "", fmt.Errorf("send chunk: %w", err)
	}
	resp, err := stream.CloseAndReceive()
	if err != nil {
		return "", fmt.Errorf("close upload stream: %w", err)
	}
	mediaID := resp.Msg.GetMediaId()
	if mediaID == "" {
		return "", errors.New("files service returned empty media_id")
	}
	return mediaID, nil
}

// setProfileAvatar writes the file id (and the original source URL for
// display fallback) back onto the profile's Properties, preserving any
// keys already present.
func (e *ProfileAvatarSyncEvent) setProfileAvatar(
	ctx context.Context, profileID string, existing map[string]string, mediaID, sourceURL string,
) error {
	merged := make(map[string]any, len(existing)+2)
	for k, v := range existing {
		merged[k] = v
	}
	merged[profilePropAvatarFileID] = mediaID
	merged[profilePropAvatarURL] = sourceURL

	props, err := structpb.NewStruct(merged)
	if err != nil {
		return fmt.Errorf("build properties struct: %w", err)
	}
	_, err = e.profileCli.Update(ctx, connect.NewRequest(&profilev1.UpdateRequest{
		Id:         profileID,
		Properties: props,
	}))
	return err
}

// profileProperties extracts the string-string view of a profile's
// Properties Struct. Non-string values are skipped (Profile allows any
// Struct value, but our keys are all string).
func profileProperties(profile *profilev1.ProfileObject) map[string]string {
	out := map[string]string{}
	if profile == nil {
		return out
	}
	props := profile.GetProperties()
	if props == nil {
		return out
	}
	for k, v := range props.AsMap() {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// sanitiseProvider collapses the provider name to a short safe slug used in
// the uploaded filename. Unknown providers become "external".
func sanitiseProvider(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		default:
			return -1
		}
	}, s)
	if s == "" {
		return "external"
	}
	return s
}
