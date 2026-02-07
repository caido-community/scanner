<script setup lang="ts">
import Failed from "./Failed.vue";
import Loading from "./Loading.vue";
import Success from "./Success.vue";

import InvalidState from "@/components/common/InvalidState.vue";
import { type ChecksState } from "@/types/checks";
import { type ConfigState } from "@/types/config";

const { checksState, configState } = defineProps<{
  checksState: ChecksState;
  configState: ConfigState;
}>();
</script>

<template>
  <Loading
    v-if="checksState.type === 'Loading' || configState.type === 'Loading'"
  />
  <Failed
    v-else-if="checksState.type === 'Error' || configState.type === 'Error'"
  />
  <Success
    v-else-if="checksState.type === 'Success' && configState.type === 'Success'"
    :state="checksState"
    :config-state="configState"
  />
  <InvalidState v-else />
</template>
