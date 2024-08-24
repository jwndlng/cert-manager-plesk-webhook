# Image name based on the Docker context directory
IMAGE_NAME := "cert-manager-plesk-webhook"

# Default target
.PHONY: all build run

all: build

build:
	docker build -t $(IMAGE_NAME) -f Dockerfile .

run:
	docker run -d --name $(IMAGE_NAME) $(IMAGE_NAME)
