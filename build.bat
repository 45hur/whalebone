docker stop resolver
docker rm resolver
docker build . -t resolver
docker run -it -v C:\var\whalebone:/var/whalebone --cap-add=NET_RAW --cap-add=NET_ADMIN -e DEBUGLOG=1 --net=host --name=resolver resolver