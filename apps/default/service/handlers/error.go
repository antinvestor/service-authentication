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

package handlers

import (
	"net/http"
)

func (h *AuthServer) ErrorEndpoint(rw http.ResponseWriter, req *http.Request) error {

	errorTitle := req.FormValue("error")
	errorDescription := req.FormValue("error_description")

	payload := h.initTemplatePayloadWithI18n(req.Context(), req)
	payload["errorTitle"] = errorTitle
	payload["errorDescription"] = errorDescription

	rw.Header().Set("Content-Type", "text/html")
	rw.WriteHeader(http.StatusInternalServerError)
	err := errorTmpl.Execute(rw, payload)

	return err
}
