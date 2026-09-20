{{/* Load the bundled copy of deploy/images.env; Helm follows the source symlink when packaging. */}}
{{- define "unrelated.images.default" -}}
{{- $prefix := printf "%s=" .key -}}
{{- $value := "" -}}
{{- range splitList "\n" (.root.Subcharts.images.Files.Get "images.env") -}}
  {{- if hasPrefix $prefix . -}}
    {{- $value = trimPrefix $prefix . | trim -}}
  {{- end -}}
{{- end -}}
{{- required (printf "missing shared image default %s" .key) $value -}}
{{- end -}}

{{/* Explicit repository/tag overrides keep their existing Helm interface. */}}
{{- define "unrelated.images.ref" -}}
{{- $default := include "unrelated.images.default" . -}}
{{- $repository := .image.repository | default (regexReplaceAll ":[^:]+$" $default "") -}}
{{- $tag := .image.tag | default (regexFind "[^:]+$" $default) -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
