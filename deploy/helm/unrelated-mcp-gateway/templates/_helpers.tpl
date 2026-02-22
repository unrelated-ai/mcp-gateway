{{- define "unrelated-mcp-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "unrelated-mcp-gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "unrelated-mcp-gateway.name" . -}}
{{- end -}}
{{- end -}}

{{- define "unrelated-mcp-gateway.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "unrelated-mcp-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "unrelated-mcp-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "unrelated-mcp-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "unrelated-mcp-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "unrelated-mcp-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "unrelated-mcp-gateway.dataServiceName" -}}
{{- include "unrelated-mcp-gateway.fullname" . -}}
{{- end -}}

{{- define "unrelated-mcp-gateway.adminServiceName" -}}
{{- printf "%s-admin" (include "unrelated-mcp-gateway.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "unrelated-mcp-gateway.inlineSecretName" -}}
{{- printf "%s-inline-secrets" (include "unrelated-mcp-gateway.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
