{{- define "unrelated-mcp-gateway-ui.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "unrelated-mcp-gateway-ui.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "unrelated-mcp-gateway-ui.name" . -}}
{{- end -}}
{{- end -}}

{{- define "unrelated-mcp-gateway-ui.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "unrelated-mcp-gateway-ui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "unrelated-mcp-gateway-ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "unrelated-mcp-gateway-ui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "unrelated-mcp-gateway-ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "unrelated-mcp-gateway-ui.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "unrelated-mcp-gateway-ui.inlineSecretName" -}}
{{- printf "%s-inline-secrets" (include "unrelated-mcp-gateway-ui.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
