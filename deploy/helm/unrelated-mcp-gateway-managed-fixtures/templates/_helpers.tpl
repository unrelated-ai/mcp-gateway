{{- define "unrelated-mcp-gateway-managed-fixtures.name" -}}
{{- default .Chart.Name .Values.nameOverride | lower | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "unrelated-mcp-gateway-managed-fixtures.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "unrelated-mcp-gateway-managed-fixtures.name" . -}}
{{- end -}}
{{- end -}}

{{- define "unrelated-mcp-gateway-managed-fixtures.labels" -}}
app.kubernetes.io/name: {{ include "unrelated-mcp-gateway-managed-fixtures.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name | lower }}-{{ .Chart.Version | replace "+" "_" }}
{{- end -}}
