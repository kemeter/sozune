{{- define "sozune.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sozune.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/* Cluster-scoped objects are shared by every namespace: the name carries
the release namespace. */}}
{{- define "sozune.clusterName" -}}
{{- printf "%s-%s" .Release.Namespace (include "sozune.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sozune.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "sozune.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "sozune.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sozune.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "sozune.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sozune.fullname" .) .Values.serviceAccount.name }}
{{- else if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- fail "serviceAccount.name is required with serviceAccount.create=false: the chart binds its role to that account, which must not be the namespace's default one" }}
{{- end }}
{{- end }}

{{/* config.yaml, with the release-bound parts of the Kubernetes provider. */}}
{{- define "sozune.config" -}}
{{- $config := deepCopy .Values.config }}
{{- $providers := default dict $config.providers }}
{{- $kubernetes := default dict $providers.kubernetes }}
{{- $_ := set $kubernetes "ingress_class" .Values.ingressClass.name }}
{{- if and .Values.service.publishAddress (eq .Values.service.type "LoadBalancer") }}
{{- $_ := set $kubernetes "publish_service" (printf "%s/%s" .Release.Namespace (include "sozune.fullname" .)) }}
{{- end }}
{{- $_ := set $providers "kubernetes" $kubernetes }}
{{- /* ACME writes where the certificate volume is mounted. */}}
{{- if $config.acme }}
{{- $_ := set $config.acme "certs_dir" .Values.persistence.mountPath }}
{{- end }}
{{- $_ := set $config "providers" $providers }}
{{- toYaml $config }}
{{- end }}
