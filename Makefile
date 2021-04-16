build:
	GOOS=linux CGO_ENABLED=0 go build *.go

invoke:
	sam local invoke  "cfsgUpdater" -e test/event.json

.PHONY: build invoke
