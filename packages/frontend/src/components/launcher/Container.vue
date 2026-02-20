<script setup lang="ts">
import Button from "primevue/button";
import SelectButton from "primevue/selectbutton";

import { useStepper } from "./useStepper";

import { provideSDK } from "@/plugins/sdk";
import { useLauncher } from "@/stores/launcher";
import { type FrontendSDK } from "@/types";

const {
  steps,
  currentStepIndex,
  currentStep,
  canGoPrevious,
  isLastStep,
  goNext,
  goPrevious,
} = useStepper();

const { sdk, incrementCount } = defineProps<{
  sdk: FrontendSDK;
  incrementCount: () => void;
}>();

provideSDK(sdk);

const launcher = useLauncher();
</script>

<template>
  <div id="plugin--scanner" class="w-[900px] h-[500px] flex flex-col gap-2">
    <div class="flex-shrink-0">
      <SelectButton
        v-model="currentStepIndex"
        :options="steps.map((_, index) => index)"
      >
        <template #option="{ option }">
          {{ steps[option]?.label }}
        </template>
      </SelectButton>
    </div>
    <div class="flex-1 overflow-auto">
      <component :is="currentStep?.component" />
    </div>
    <div class="flex items-center justify-end gap-2 flex-shrink-0">
      <Button
        v-if="canGoPrevious"
        label="Previous"
        icon="fas fa-chevron-left"
        severity="info"
        outlined
        @mousedown="goPrevious"
      />
      <Button
        v-if="!isLastStep"
        label="Next"
        icon="fas fa-chevron-right"
        icon-pos="right"
        severity="info"
        outlined
        @mousedown="goNext"
      />
      <Button
        label="Run Scan"
        icon="fas fa-play"
        severity="success"
        :disabled="launcher.isLoading"
        :loading="launcher.isLoading"
        @mousedown="launcher.onSubmit(sdk, incrementCount)"
      />
    </div>
  </div>
</template>
