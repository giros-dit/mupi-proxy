FROM vyos/rolling:1.3
#FROM vyos:1.4
#FROM vyosimg/vyos-1.3

RUN mkdir /config
RUN sed -i -e 's/pimd=yes/pimd=no/' /etc/frr/daemons

CMD /sbin/init
