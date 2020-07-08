FROM golang:alpine
RUN mkdir /app
COPY . /app
RUN cd /app && go build discloudflR.go
WORKDIR /app
ENTRYPOINT ["./discloudflR"]
