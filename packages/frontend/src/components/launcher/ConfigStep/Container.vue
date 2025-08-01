<script setup lang="ts">
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import SelectButton from "primevue/selectbutton";

import { useForm } from "./useForm";

const {
  form,
  aggressivityOptions,
  severityOptions,
  scopeOptions,
  inScopeOnly,
  readableTimeout,
} = useForm();
</script>

<template>
  <div class="w-full flex flex-col gap-6 py-3">
    <div class="flex flex-col gap-2">
      <div>
        <label class="block text-sm font-medium text-surface-200">Title</label>
        <small class="block text-sm text-surface-400">
          Enter a descriptive title for your scan
        </small>
      </div>
      <InputText
        v-model="form.title"
        placeholder="Enter a descriptive title for your scan"
        class="w-full"
      />
    </div>

    <div
      class="grid grid-cols-3 gap-6"
      style="grid-template-columns: 1.5fr 2fr 1fr"
    >
      <div class="flex flex-col gap-2">
        <div>
          <label class="block text-sm font-medium text-surface-200">
            Aggressivity
          </label>
          <small class="block text-sm text-surface-400">
            Level of aggressiveness for the scan
          </small>
        </div>
        <SelectButton
          v-model="form.config.aggressivity"
          :options="aggressivityOptions"
          :allow-empty="false"
          option-label="label"
          option-value="value"
          :pt="{
            root: {
              style: 'width: fit-content; border-color: var(--p-surface-700)',
            },
          }"
        />
      </div>

      <div class="flex flex-col gap-2">
        <div>
          <label class="block text-sm font-medium text-surface-200">
            Severities
          </label>
          <small class="block text-sm text-surface-400">
            Select the severities to report
          </small>
        </div>
        <SelectButton
          v-model="form.config.severities"
          :options="severityOptions"
          option-label="label"
          option-value="value"
          multiple
          :pt="{
            root: {
              style: 'width: fit-content; border-color: var(--p-surface-700)',
            },
          }"
        />
      </div>

      <div class="flex flex-col gap-2">
        <div>
          <label class="block text-sm font-medium text-surface-200">
            Scope
          </label>
          <small class="block text-sm text-surface-400">
            Define the scope of the scan
          </small>
        </div>
        <SelectButton
          v-model="inScopeOnly"
          :options="scopeOptions"
          option-label="label"
          option-value="value"
          :allow-empty="false"
          :pt="{
            root: {
              style: 'width: fit-content; border-color: var(--p-surface-700)',
            },
          }"
        />
      </div>

      <div class="flex flex-col gap-2">
        <div>
          <label class="block text-sm font-medium text-surface-200">
            Checks Concurrency
          </label>
          <small class="block text-sm text-surface-400">
            Number of checks to run simultaneously
          </small>
        </div>
        <InputNumber
          v-model="form.config.concurrentChecks"
          :min="1"
          :max="100"
          class="w-full"
        />
      </div>

      <div class="flex flex-col gap-2">
        <div>
          <label class="block text-sm font-medium text-surface-200">
            Requests Concurrency
          </label>
          <small class="block text-sm text-surface-400">
            Number of requests to send simultaneously
          </small>
        </div>
        <InputNumber
          v-model="form.config.concurrentRequests"
          :min="1"
          :max="100"
          class="w-full"
        />
      </div>

      <div class="flex flex-col gap-2">
        <div>
          <label class="block text-sm font-medium text-surface-200">
            Requests Delay (ms)
          </label>
          <small class="block text-sm text-surface-400">
            Delay between requests
          </small>
        </div>
        <InputNumber
          v-model="form.config.requestsDelayMs"
          :min="0"
          class="w-full"
        />
      </div>

      <div class="flex flex-col gap-2">
        <div>
          <label
            class="block text-sm font-medium text-surface-200 flex items-center gap-1"
          >
            Timeout (seconds)
            <span
              v-if="readableTimeout"
              class="text-surface-500 text-xs font-normal"
            >
              ({{ readableTimeout }})
            </span>
          </label>
          <small class="block text-sm text-surface-400">
            Maximum time to wait for scan to finish
          </small>
        </div>
        <InputNumber
          :model-value="form.config.scanTimeout"
          :min="1"
          placeholder="600"
          class="w-full"
          @input="form.config.scanTimeout = $event.value"
        />
      </div>

      <div class="flex flex-col gap-2">
        <div>
          <label class="block text-sm font-medium text-surface-200">
            Targets Concurrency
          </label>
          <small class="block text-sm text-surface-400">
            Number of targets to scan simultaneously
          </small>
        </div>
        <InputNumber
          v-model="form.config.concurrentTargets"
          :min="1"
          :max="100"
          class="w-full"
        />
      </div>
    </div>
  </div>
</template>
