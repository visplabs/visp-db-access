{{- define "visp-gate.name" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "visp-gate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "visp-gate.name" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
{{- define "visp-gate.labels" -}}
app.kubernetes.io/name: visp-gate
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
