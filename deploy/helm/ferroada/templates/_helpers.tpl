{{/*
Expand the name of the chart.
*/}}
{{- define "ferroada.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ferroada.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ferroada.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ferroada.labels" -}}
helm.sh/chart: {{ include "ferroada.chart" . }}
{{ include "ferroada.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "ferroada.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ferroada.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "ferroada.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ferroada.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "ferroada.secretName" -}}
{{- if .Values.ferroada.existingSecret }}
{{- .Values.ferroada.existingSecret }}
{{- else }}
{{- include "ferroada.fullname" . }}
{{- end }}
{{- end }}

{{- define "ferroada.configMapName" -}}
{{- if .Values.config.existingConfigMap }}
{{- .Values.config.existingConfigMap }}
{{- else }}
{{- include "ferroada.fullname" . }}
{{- end }}
{{- end }}

{{- define "ferroada.hasToml" -}}
{{- if or .Values.config.toml .Values.config.existingConfigMap -}}true{{- end -}}
{{- end }}

{{- define "ferroada.validate" -}}
{{- $bind := .Values.ferroada.dashboardBind | toString }}
{{- if and (ne $bind "127.0.0.1") (ne $bind "::1") }}
{{- fail "ferroada.dashboardBind tem de ser loopback (127.0.0.1 ou ::1). O dashboard não é Service." }}
{{- end }}
{{- if eq (.Values.service.port | int) 9000 }}
{{- fail "service.port não pode ser 9000 — essa porta é do dashboard, não do proxy" }}
{{- end }}
{{- if eq (.Values.service.port | int) (.Values.ferroada.dashboardPort | int) }}
{{- fail "service.port não pode ser a porta do dashboard — o painel não é Service/Ingress" }}
{{- end }}
{{- end }}
