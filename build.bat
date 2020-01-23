docker stop resolver
docker rm resolver
docker build . -t resolver
docker run -it -v C:\var\whalebone:/var/whalebone -v C:\var\log\whalebone:/var/log/whalebone -e DEBUGLOG=1 --cap-add=NET_RAW --cap-add=NET_ADMIN --net=host --name=resolver resolver