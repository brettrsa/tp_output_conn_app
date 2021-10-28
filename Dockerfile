FROM python:3.8-alpine

# use copy instead of add
COPY application.py /srv/app/


# create user and set ownership and permissions as required
RUN adduser -D app_user && chown -R app_user /srv/app

# set workdir
WORKDIR /srv/app/

# set port to tcp 5000
EXPOSE 8000

# set user,use entrypoint and cmd
USER app_user
ENTRYPOINT ["python3"] 
CMD ["/srv/app/application.py"]

