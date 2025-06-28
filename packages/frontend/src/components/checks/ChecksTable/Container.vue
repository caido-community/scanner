<script setup lang="ts">
import Failed from "./Failed.vue";
import Loading from "./Loading.vue";
import Success from "./Success.vue";

import InvalidState from "@/components/common/InvalidState.vue";
import { type ChecksState } from "@/types/checks";

defineProps<{
  checksState: ChecksState;
}>();
</script>

<template>
  <Loading v-if="checksState.type === 'Loading'" />
  <Failed v-else-if="checksState.type === 'Error'" />
  <Success v-else-if="checksState.type === 'Success'" :state="checksState" />
  <InvalidState v-else />
</template>
