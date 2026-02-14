<script setup lang="ts">
import Button from "primevue/button";
import Checkbox from "primevue/checkbox";
import { type BasicRequest } from "shared";
import { computed, ref, watch } from "vue";
import { RecycleScroller } from "vue-virtual-scroller";

import { useSDK } from "@/plugins/sdk";
import { useLauncher } from "@/stores/launcher";

const sdk = useSDK();
const launcher = useLauncher();
const { form } = launcher;

const selectedTargetIDs = ref<Array<BasicRequest["id"]>>([]);

const selectedTargetIDsSet = computed(() => new Set(selectedTargetIDs.value));

const selectedTargetsCount = computed(() => {
  return form.targets.filter((target) =>
    selectedTargetIDsSet.value.has(target.id),
  ).length;
});

const isTargetSelected = (targetID: BasicRequest["id"]) =>
  selectedTargetIDsSet.value.has(targetID);

const toggleTargetSelection = (targetID: BasicRequest["id"]) => {
  if (selectedTargetIDsSet.value.has(targetID)) {
    selectedTargetIDs.value = selectedTargetIDs.value.filter(
      (id) => id !== targetID,
    );
    return;
  }

  selectedTargetIDs.value = [...selectedTargetIDs.value, targetID];
};

watch(
  () => form.targets,
  (targets) => {
    const targetIDs = new Set(targets.map((target) => target.id));
    selectedTargetIDs.value = selectedTargetIDs.value.filter((targetID) =>
      targetIDs.has(targetID),
    );
  },
);

const handleDeleteSelected = () => {
  const selectedIDsSet = new Set(selectedTargetIDs.value);
  const remainingTargets = form.targets.filter(
    (target) => !selectedIDsSet.has(target.id),
  );

  if (remainingTargets.length === 0) {
    sdk.window.showToast(
      "Cannot delete all requests. At least one request must remain.",
      { variant: "warning" },
    );
    return;
  }

  form.targets = remainingTargets;
  selectedTargetIDs.value = [];
};
</script>
<template>
  <div class="flex flex-col h-full py-1">
    <div class="py-2 flex justify-between items-center h-8 flex-shrink-0">
      <div class="text-sm text-surface-400">
        {{ form.targets.length }} unique requests
      </div>
      <div class="h-8 flex items-center">
        <Button
          v-if="selectedTargetsCount > 0"
          icon="fas fa-trash"
          severity="danger"
          size="small"
          :label="`Delete ${selectedTargetsCount} selected`"
          @click="handleDeleteSelected"
        />
      </div>
    </div>

    <div class="flex-1 min-h-0 flex flex-col">
      <div
        class="flex items-center text-surface-0/70 bg-surface-800 text-sm flex-shrink-0"
        style="scrollbar-gutter: stable"
      >
        <div class="w-12 flex-shrink-0 px-2" />
        <div class="flex-[10] px-2 py-[0.375rem] min-w-0">Method</div>
        <div class="flex-[28] px-2 py-[0.375rem] min-w-0">Host</div>
        <div class="flex-[28] px-2 py-[0.375rem] min-w-0">Path</div>
        <div class="flex-[34] px-2 py-[0.375rem] min-w-0">Query</div>
      </div>

      <RecycleScroller
        class="flex-1 overflow-auto"
        style="scrollbar-gutter: stable"
        :items="form.targets"
        :item-size="34"
        key-field="id"
      >
        <template #default="{ item, index }">
          <div
            class="flex items-center h-[34px] text-sm"
            :class="index % 2 === 0 ? 'bg-surface-900' : 'bg-surface-800'"
          >
            <div class="w-12 flex-shrink-0 px-2">
              <Checkbox
                :model-value="isTargetSelected(item.id)"
                binary
                @update:model-value="toggleTargetSelection(item.id)"
              />
            </div>
            <div class="flex-[10] px-2 min-w-0">
              <div class="truncate">{{ item.method }}</div>
            </div>
            <div class="flex-[28] px-2 min-w-0">
              <div class="font-medium truncate">
                {{ item.host }}:{{ item.port }}
              </div>
            </div>
            <div class="flex-[28] px-2 min-w-0">
              <div class="truncate">{{ item.path }}</div>
            </div>
            <div class="flex-[34] px-2 min-w-0">
              <div class="truncate">{{ item.query }}</div>
            </div>
          </div>
        </template>
      </RecycleScroller>
    </div>
  </div>
</template>
