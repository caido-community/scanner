<script setup lang="ts">
import Failed from "./Failed.vue";
import Loading from "./Loading.vue";
import Success from "./Success.vue";

import InvalidState from "@/components/common/InvalidState.vue";
import { type ConfigState } from "@/types/config";

defineProps<{
  configState: ConfigState;
}>();
</script>

<template>
  <Loading v-if="configState.type === 'Loading'" />
  <Failed v-else-if="configState.type === 'Error'" />
  <Success v-else-if="configState.type === 'Success'" :state="configState" />
  <InvalidState v-else />
</template>
