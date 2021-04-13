build:
	GOOS=linux CGO_ENABLED=0 go build main.go

invoke:
	sam local invoke  "cfsgUpdater" -e test/event.json

.PHONY: build invoke
