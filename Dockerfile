FROM gcr.io/google_appengine/golang

RUN apt-get -qq update
RUN apt-get -qqy install nmap
