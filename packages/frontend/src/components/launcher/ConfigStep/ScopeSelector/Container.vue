<script setup lang="ts">
import { onClickOutside } from "@vueuse/core";
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import { computed, ref } from "vue";

const {
  options,
  placeholder = "All requests (no scope filter)",
  disabled = false,
} = defineProps<{
  options: Array<{ label: string; value: string }>;
  placeholder?: string;
  disabled?: boolean;
}>();
const selectedValues = defineModel<Array<string>>({ default: [] });
const isOpen = ref(false);
const containerRef = ref<HTMLElement>();

const selectedOptions = computed(() => {
  const selectedSet = new Set(selectedValues.value);
  return options.filter((option) => selectedSet.has(option.value));
});

const selectedCount = computed(() => selectedOptions.value.length);

const triggerLabel = computed(() => {
  if (selectedCount.value === 0) {
    return placeholder;
  }

  if (selectedCount.value === 1) {
    return "1 scope selected";
  }

  return `${selectedCount.value} scopes selected`;
});

const isSelected = (value: string) => selectedValues.value.includes(value);

const toggleOpen = () => {
  if (disabled) {
    return;
  }

  isOpen.value = !isOpen.value;
};

const toggleOption = (value: string) => {
  if (isSelected(value)) {
    selectedValues.value = selectedValues.value.filter(
      (item) => item !== value,
    );
    return;
  }

  selectedValues.value = [...selectedValues.value, value];
};

onClickOutside(containerRef, () => {
  isOpen.value = false;
});
</script>

<template>
  <div ref="containerRef" class="relative w-full min-w-0">
    <Button
      type="button"
      :disabled="disabled"
      class="w-full"
      :pt="{
        root: {
          class:
            'w-full min-w-0 flex items-center justify-between gap-2 leading-none m-0 py-2 px-3 rounded-md text-surface-800 dark:text-white/80 bg-surface-0 dark:bg-surface-950 border border-surface-300 dark:border-surface-700 hover:border-surface-400 dark:hover:border-surface-600 focus:outline-none focus:outline-offset-0 focus:ring-1 focus:ring-secondary-500 dark:focus:ring-secondary-400 focus:z-10 transition-colors duration-200 disabled:opacity-50 disabled:cursor-not-allowed',
        },
      }"
      @mousedown.prevent="toggleOpen"
    >
      <span class="min-w-0 flex-1 truncate text-left">{{ triggerLabel }}</span>
      <i
        :class="[
          'fas fa-chevron-down text-xs shrink-0 text-surface-500 transition-transform',
          isOpen ? 'rotate-180' : '',
        ]"
      />
    </Button>

    <div
      v-if="isOpen"
      class="absolute z-[5000] mt-1 w-full min-w-0 rounded-md border border-surface-300 bg-surface-0 shadow-md dark:border-surface-700 dark:bg-surface-900"
    >
      <div class="max-h-56 overflow-auto py-1">
        <button
          v-for="option in options"
          :key="option.value"
          type="button"
          class="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-surface-800 hover:bg-surface-100 dark:text-surface-200 dark:hover:bg-surface-800"
          @mousedown.prevent="toggleOption(option.value)"
        >
          <Checkbox
            :model-value="isSelected(option.value)"
            binary
            class="pointer-events-none"
          />
          <span class="truncate">{{ option.label }}</span>
        </button>

        <div
          v-if="options.length === 0"
          class="px-3 py-2 text-sm text-surface-500"
        >
          No available scopes
        </div>
      </div>
    </div>
  </div>
</template>
