SERVICE := secretchannel
DESTDIR ?= dist_root
SERVICEDIR ?= /srv/$(SERVICE)

.PHONY: build install

build:
	cd secretchannel/src && npm install

install: build
	mkdir -p $(DESTDIR)$(SERVICEDIR)
	cp docker-compose.release.yml $(DESTDIR)$(SERVICEDIR)/docker-compose.yml
	mkdir -p $(DESTDIR)$(SERVICEDIR)/
	cp -r secretchannel $(DESTDIR)$(SERVICEDIR)/
	mkdir -p $(DESTDIR)/etc/systemd/system/faustctf.target.wants/
	ln -s /etc/systemd/system/docker-compose@.service $(DESTDIR)/etc/systemd/system/faustctf.target.wants/docker-compose@$(SERVICE).service

