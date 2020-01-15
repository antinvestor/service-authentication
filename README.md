# service-auth

This service is responsible for authentication throught the system.
It relies on profile service to be working for it to perform optimally.


Development:
***

To update the profile api one needs to run the following grpc update command.

```protoc -I ../api/service/profile/v1/ ../api/service/profile/v1/profile.proto --go_out=plugins=grpc:grpc/profile```



