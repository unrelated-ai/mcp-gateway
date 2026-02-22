{{- define "unrelated-mcp-postgres.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "unrelated-mcp-postgres.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "unrelated-mcp-postgres.name" . -}}
{{- end -}}
{{- end -}}

{{- define "unrelated-mcp-postgres.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "unrelated-mcp-postgres.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "unrelated-mcp-postgres.selectorLabels" -}}
app.kubernetes.io/name: {{ include "unrelated-mcp-postgres.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "unrelated-mcp-postgres.secretName" -}}
{{- if .Values.auth.existingSecret.name -}}
{{- .Values.auth.existingSecret.name -}}
{{- else -}}
{{- printf "%s-auth" (include "unrelated-mcp-postgres.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
