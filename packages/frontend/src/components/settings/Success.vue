<script setup lang="ts">
import { ScanAggressivity, Severity } from "engine";
import Card from "primevue/card";
import InputNumber from "primevue/inputnumber";
import MultiSelect from "primevue/multiselect";
import Select from "primevue/select";
import SelectButton from "primevue/selectbutton";
import ToggleSwitch from "primevue/toggleswitch";
import { computed, ref, toRef } from "vue";

import { useForm } from "./useForm";

import { type ConfigState } from "@/types/config";

const { state } = defineProps<{
  state: ConfigState & { type: "Success" };
}>();

const {
  passiveEnabled,
  passiveAggressivity,
  passiveScopeIDs,
  scopeOptions,
  passiveSeverities,
  passiveConcurrentScans,
  passiveConcurrentRequests,
  defaultPresetName,
  requestTimeout,
  presetOptions,
} = useForm(toRef(() => state));

const severityOptions = computed(() =>
  Object.values(Severity).map((severity) => ({
    label: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: severity,
  })),
);

const aggressivityOptions = computed(() =>
  Object.values(ScanAggressivity).map((aggressivity) => ({
    label: aggressivity.charAt(0).toUpperCase() + aggressivity.slice(1),
    value: aggressivity,
  })),
);

const sectionOptions = [
  { label: "General", value: "general" },
  { label: "Filtering", value: "filtering" },
  { label: "Execution", value: "execution" },
] as const;

type SettingsSection = (typeof sectionOptions)[number]["value"];

const activeSection = ref<SettingsSection>("general");
</script>

<template>
  <div class="flex h-full flex-col gap-1 overflow-y-auto">
    <Card
      class="h-fit"
      :pt="{
        body: { class: 'h-fit p-0' },
        content: { class: 'h-fit flex flex-col' },
      }"
    >
      <template #content>
        <div class="flex items-center justify-between p-4">
          <div>
            <h3 class="text-lg font-semibold">Settings</h3>
            <p class="text-sm text-surface-300">
              Configure passive and active scanner settings
            </p>
          </div>
        </div>
      </template>
    </Card>

    <Card
      class="h-full"
      :pt="{
        body: { class: 'h-full p-0' },
        content: { class: 'h-full flex flex-col' },
      }"
    >
      <template #content>
        <div class="flex h-full min-h-0 flex-col gap-4 p-4">
          <SelectButton
            v-model="activeSection"
            :options="sectionOptions"
            option-label="label"
            option-value="value"
            :allow-empty="false"
            class="w-fit"
          />

          <div class="flex min-h-0 flex-1 flex-col overflow-y-auto pr-1">
            <template v-if="activeSection === 'general'">
              <div class="flex flex-col gap-4">
                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex flex-col gap-0">
                    <label class="text-base font-medium">Default Preset</label>
                    <p class="text-sm text-surface-400">
                      The preset that will be applied to new projects
                    </p>
                  </div>
                  <Select
                    v-model="defaultPresetName"
                    :options="presetOptions"
                    option-label="label"
                    option-value="value"
                    placeholder="Select a preset"
                    class="w-48"
                  />
                </div>

                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex min-w-0 flex-col gap-0">
                    <label class="text-base font-medium"
                      >Request Timeout (seconds)</label
                    >
                    <p class="text-sm text-surface-400">
                      Maximum time to wait for a single HTTP request to complete
                    </p>
                  </div>
                  <InputNumber
                    v-model="requestTimeout"
                    :min="1"
                    :max="600"
                    placeholder="120"
                    class="w-full"
                  />
                </div>

                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex flex-col gap-0">
                    <label class="text-base font-medium"
                      >Enable Passive Scanner</label
                    >
                    <p class="text-sm text-surface-400">
                      When enabled, the scanner will automatically analyze HTTP
                      traffic for vulnerabilities
                    </p>
                  </div>
                  <div class="flex items-center pt-1">
                    <ToggleSwitch v-model="passiveEnabled" />
                  </div>
                </div>
              </div>
            </template>

            <template v-else-if="activeSection === 'filtering'">
              <div class="flex flex-col gap-4">
                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex flex-col gap-0">
                    <label class="text-base font-medium"
                      >Passive Scope Filter</label
                    >
                    <p class="text-sm text-surface-400">
                      Only analyze requests matching the selected scopes
                    </p>
                  </div>
                  <MultiSelect
                    v-model="passiveScopeIDs"
                    :options="scopeOptions"
                    option-label="label"
                    option-value="value"
                    display="comma"
                    placeholder="All requests (no scope filter)"
                    :disabled="!passiveEnabled"
                    class="max-w-md"
                  />
                </div>

                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex flex-col gap-0">
                    <label class="text-base font-medium">Severities</label>
                    <p class="text-sm text-surface-400">
                      Select which severity levels to include in passive
                      scanning
                    </p>
                  </div>
                  <SelectButton
                    v-model="passiveSeverities"
                    :options="severityOptions"
                    option-label="label"
                    option-value="value"
                    :disabled="!passiveEnabled"
                    multiple
                    class="w-full"
                    :pt="{
                      root: { class: 'w-full flex flex-wrap gap-2' },
                    }"
                  />
                </div>
              </div>
            </template>

            <template v-else>
              <div class="flex flex-col gap-4">
                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex flex-col gap-0">
                    <label class="text-base font-medium">Scans Concurrency</label>
                    <p class="text-sm text-surface-400">
                      Number of scans that can run simultaneously
                    </p>
                  </div>
                  <div class="flex flex-col gap-2">
                    <InputNumber
                      v-model="passiveConcurrentScans"
                      :min="1"
                      :max="30"
                      :disabled="!passiveEnabled"
                      class="w-full"
                    />
                    <div
                      v-if="passiveConcurrentScans > 8"
                      class="text-xs text-orange-400"
                    >
                      High values may cause performance issues
                    </div>
                  </div>
                </div>

                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex flex-col gap-0">
                    <label class="text-base font-medium"
                      >Requests Concurrency</label
                    >
                    <p class="text-sm text-surface-400">
                      Number of requests to send simultaneously during single
                      scan execution
                    </p>
                  </div>
                  <InputNumber
                    v-model="passiveConcurrentRequests"
                    :min="1"
                    :max="100"
                    :disabled="!passiveEnabled"
                    class="w-full"
                  />
                </div>

                <div class="flex min-w-0 flex-col gap-2">
                  <div class="flex flex-col gap-0">
                    <label class="text-base font-medium">Scan Aggressivity</label>
                    <p class="text-sm text-surface-400">
                      Controls the aggressiveness of passive scanning checks.
                      Lower means faster scanning and less accurate results.
                    </p>
                  </div>
                  <SelectButton
                    v-model="passiveAggressivity"
                    :options="aggressivityOptions"
                    option-label="label"
                    option-value="value"
                    :disabled="!passiveEnabled"
                    class="w-full"
                    :pt="{
                      root: { class: 'w-full flex flex-wrap gap-2' },
                    }"
                  />
                </div>
              </div>
            </template>
          </div>
        </div>
      </template>
    </Card>
  </div>
</template>
