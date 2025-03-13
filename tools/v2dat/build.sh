
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o v2dat -trimpath -ldflags -s -w -buildid= .
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o v2dat-arm -trimpath -ldflags "-s -w -buildid=" .
