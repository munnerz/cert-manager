{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "cert-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "cert-manager.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- $fullname := printf "%s-%s" $name .Release.Name -}}
{{- default $fullname .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cert-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "cert-manager.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "cert-manager.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Create the name of the service account to use for webhooks
*/}}
{{- define "cert-manager.webhook.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (printf "%s-webhook" (include "cert-manager.fullname" .)) .Values.webhook.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.webhook.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "cert-manager.webhook.serviceName" -}}
{{ printf "%s-webhook" (include "cert-manager.fullname" .) }}
{{- end -}}

{{- define "cert-manager.webhook.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "cert-manager.fullname" .) }}
{{- end -}}

{{- define "cert-manager.webhook.issuer" -}}
{{ printf "%s-webhook" (include "cert-manager.fullname" .) }}
{{- end -}}

{{- define "cert-manager.webhook.rootCACertificate" -}}
{{ printf "%s-webhook-ca" (include "cert-manager.fullname" .) }}
{{- end -}}

{{- define "cert-manager.webhook.certificate" -}}
{{ printf "%s-webhook-tls" (include "cert-manager.fullname" .) }}
{{- end -}}
