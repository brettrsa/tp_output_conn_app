########################
HOW-TO-INSTALL AND RUN #
########################

# Build the container from the Dockerfile
docker build -t local_app/local_app .

# Run the docker with the commands below, 
docker run -d --net=host local_app/local_app



