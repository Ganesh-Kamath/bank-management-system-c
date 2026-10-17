FROM gcc:12-bullseye AS build
WORKDIR /app
COPY Bankmanagement.c index.html ./
RUN gcc -std=c11 -O2 -Wall -Wextra -o Bankmanagement Bankmanagement.c -lm

FROM debian:bullseye-slim
WORKDIR /app
COPY --from=build /app/Bankmanagement /app/index.html ./
EXPOSE 8080
CMD ["./Bankmanagement"]
