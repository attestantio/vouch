# Grafana Dashboard

There is a Grafana dashboard available [here](https://grafana.com/grafana/dashboards/22199-vouch-attestant/) that can be imported in to Grafana.

## Prerequisites 

The dashboard is designed to work with version `1.9.1` of `vouch` onwards and has been tested with Grafana version `11.2.2`.

The dashboard assumes that `Prometheus` is the data source being used and has a variable named `instance` that is used to differentiate between different `vouch` instances within the metrics.

## Installation

In Grafana:

* Navigate to `Dashboards`, click `New` and then `Import`.
* Enter the dashboard ID, 22199, in the `Find and import dashboards` field then click `Load`.
* Change the dashboard name (if required), select the Prometheus data source and click `Import`.

Please refer to the [Grafana Docs](https://grafana.com/docs/grafana/latest/dashboards/build-dashboards/import-dashboards/#import-a-dashboard) if you require more details.

## Post Install

The `instance` variable and label are referenced on every chart, so if you wish to use a different variable or label to differentiate between `vouch` instances (e.g. `host`, `job` etc) then you may want to edit the json and replace `instance=\"$instance\"` with `<your_label>=\"$<your_variable>\"`. If you do change the variable name you will need to update the templating section from:

```yaml
      {
        "datasource": {
          "type": "prometheus",
          "uid": null
        },
        "definition": "label_values(vouch_start_time_secs, instance)",
        "hide": 0,
        "includeAll": false,
        "label": "Instance",
        "multi": false,
        "name": "instance",
        "options": [],
        "query": {
          "query": "label_values(vouch_start_time_secs, instance)",
          "refId": "StandardVariableQuery"
        },
        "refresh": 2,
        "regex": "",
        "skipUrlSync": false,
        "sort": 1,
        "tagValuesQuery": "",
        "tagsQuery": "",
        "type": "query",
        "useTags": false
      },
```

To:

```yaml
      {
        "datasource": {
          "type": "prometheus",
          "uid": null
        },
        "definition": "label_values(vouch_start_time_secs, <your_variable>)",
        "hide": 0,
        "includeAll": false,
        "label": "<your_variable_label>",
        "multi": false,
        "name": "<your_variable>",
        "options": [],
        "query": {
          "query": "label_values(vouch_start_time_secs, <your_variable>)",
          "refId": "StandardVariableQuery"
        },
        "refresh": 2,
        "regex": "",
        "skipUrlSync": false,
        "sort": 1,
        "tagValuesQuery": "",
        "tagsQuery": "",
        "type": "query",
        "useTags": false
      },
```

