FROM golang as build

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /issuer-service

FROM alpine as runner

WORKDIR /app

COPY --from=build /issuer-service /issuer-service

CMD ["/issuer-service"]