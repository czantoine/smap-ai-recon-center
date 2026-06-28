FROM grafana/grafana:latest

USER root

# Datasource
COPY ./grafana-provisioning/datasources/datasource.yml /etc/grafana/provisioning/datasources/default.yml

# Dashboards provisioning
COPY ./grafana-provisioning/dashboards/dashboards.yml /etc/grafana/provisioning/dashboards/smap.yml
COPY ./grafana-provisioning/fetch-dashboard.sh /usr/local/bin/fetch-dashboard.sh

RUN mkdir -p /var/lib/grafana/dashboards
RUN chmod +x /usr/local/bin/fetch-dashboard.sh

ENTRYPOINT ["/usr/local/bin/fetch-dashboard.sh"]
CMD ["/run.sh"]
