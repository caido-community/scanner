<script setup lang="ts">
import Card from "primevue/card";
import Dropdown from "primevue/dropdown";
import InputSwitch from "primevue/inputswitch";
import { toRefs } from "vue";

import { useForm } from "./useForm";

import { type ConfigState } from "@/types/config";

const props = defineProps<{
  state: ConfigState;
}>();

const { state } = toRefs(props);

const { passiveEnabled, passiveStrength, strengthOptions } = useForm({ state });
</script>

<template>
  <Card
    class="h-full"
    :pt="{
      body: { class: 'h-full p-0' },
      content: { class: 'h-full flex flex-col' },
    }"
  >
    <template #content>
      <div class="p-4 flex-1">
        <div class="mb-6">
          <h3 class="text-lg font-semibold">Scanner Configuration</h3>
          <p class="text-sm text-surface-300">
            Configure passive and active scanner settings
          </p>
        </div>

        <div class="space-y-6">
          <div class="space-y-4">
            <h4 class="text-md font-medium">Passive Scanner</h4>

            <div class="flex items-center justify-between">
              <div class="flex-1">
                <label class="block text-sm font-medium mb-1"
                  >Enable Passive Scanner</label
                >
                <p class="text-xs text-surface-400">
                  When enabled, the scanner will automatically analyze HTTP
                  traffic for vulnerabilities
                </p>
              </div>
              <InputSwitch v-model="passiveEnabled" />
            </div>

            <div class="flex items-center justify-between">
              <div class="flex-1">
                <label class="block text-sm font-medium mb-1"
                  >Scan Strength</label
                >
                <p class="text-xs text-surface-400">
                  Controls the aggressiveness of passive scanning checks. Lower
                  means faster scanning, less requests, but less accurate.
                </p>
              </div>
              <Dropdown
                v-model="passiveStrength"
                :options="strengthOptions"
                option-label="label"
                option-value="value"
                :disabled="!passiveEnabled"
                class="w-32"
              />
            </div>
          </div>
        </div>
      </div>
    </template>
  </Card>
</template>
