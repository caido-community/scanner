<script setup lang="ts">
import { type Finding, Severity } from "engine";
import { computed } from "vue";

const { findings } = defineProps<{
  findings: Finding[];
}>();

const findingsBySeverity = computed(() => {
  const counts = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  findings.forEach((finding) => {
    counts[finding.severity]++;
  });

  return counts;
});

const severityOrder = [
  Severity.CRITICAL,
  Severity.HIGH,
  Severity.MEDIUM,
  Severity.LOW,
  Severity.INFO,
];

const getSeverityBadgeColor = (severity: string) => {
  switch (severity) {
    case Severity.CRITICAL:
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case Severity.HIGH:
      return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case Severity.MEDIUM:
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case Severity.LOW:
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case Severity.INFO:
      return "bg-surface-500/20 text-surface-400 border-surface-500/30";
    default:
      return "bg-surface-500/20 text-surface-400 border-surface-500/30";
  }
};
</script>

<template>
  <div class="flex flex-wrap gap-2">
    <div
      v-for="severity in severityOrder"
      v-show="findingsBySeverity[severity] > 0"
      :key="severity"
      :class="[
        'px-2 py-1 rounded-md border text-xs font-medium',
        getSeverityBadgeColor(severity),
      ]"
    >
      {{ severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() }}:
      {{ findingsBySeverity[severity] }}
    </div>
    <div
      v-if="Object.values(findingsBySeverity).every((count) => count === 0)"
      class="py-1 rounded-md text-xs text-surface-500 italic h-[23px] flex items-center"
    >
      No findings found
    </div>
  </div>
</template>
