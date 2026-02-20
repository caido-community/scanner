<script setup lang="ts">
import { type Session } from "shared";
import { toRef } from "vue";
import { DynamicScroller, DynamicScrollerItem } from "vue-virtual-scroller";

import { useTable } from "./useTable";

import FindingsBySeverity from "@/components/common/FindingsBySeverity.vue";

const { session } = defineProps<{
  session: Session;
}>();

const { checksHistory } = useTable(toRef(() => session));

const columnWidths = {
  targetID: "10%",
  check: "30%",
  requests: "10%",
  findings: "30%",
  status: "20%",
} as const;
</script>

<template>
  <div class="flex-1 min-h-0 flex flex-col">
    <div class="overflow-y-scroll" style="scrollbar-gutter: stable">
      <table class="w-full border-spacing-0 border-separate table-fixed">
        <thead class="bg-surface-900">
          <tr class="text-surface-0/70">
            <th
              class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
              :style="{ width: columnWidths.targetID }"
            >
              Target ID
            </th>
            <th
              class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
              :style="{ width: columnWidths.check }"
            >
              Check
            </th>
            <th
              class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
              :style="{ width: columnWidths.requests }"
            >
              Requests
            </th>
            <th
              class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
              :style="{ width: columnWidths.findings }"
            >
              Findings
            </th>
            <th
              class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
              :style="{ width: columnWidths.status }"
            >
              Status
            </th>
          </tr>
        </thead>
      </table>
    </div>

    <div
      v-if="checksHistory.length === 0"
      class="flex-1 min-h-0 flex items-center justify-center text-surface-400"
    >
      No checks yet
    </div>

    <DynamicScroller
      v-else
      class="flex-1 overflow-auto"
      style="scrollbar-gutter: stable"
      :items="checksHistory"
      :min-item-size="38"
      key-field="id"
    >
      <template #default="{ item, index, active }">
        <DynamicScrollerItem
          :item="item"
          :active="active"
          :size-dependencies="[item.findings.length, item.status]"
        >
          <table class="w-full border-spacing-0 border-separate table-fixed">
            <tbody>
              <tr
                :class="index % 2 === 0 ? 'bg-surface-800' : 'bg-surface-900'"
              >
                <td
                  class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-top"
                  :style="{ width: columnWidths.targetID }"
                >
                  <div class="text-sm font-mono truncate">
                    {{ item.targetID }}
                  </div>
                </td>
                <td
                  class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-top"
                  :style="{ width: columnWidths.check }"
                >
                  <div class="text-sm truncate">{{ item.name }}</div>
                </td>
                <td
                  class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-top"
                  :style="{ width: columnWidths.requests }"
                >
                  <div class="text-sm font-mono">{{ item.requestsSent }}</div>
                </td>
                <td
                  class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-top"
                  :style="{ width: columnWidths.findings }"
                >
                  <FindingsBySeverity :findings="item.findings" />
                </td>
                <td
                  class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-top"
                  :style="{ width: columnWidths.status }"
                >
                  <div class="text-sm">
                    <span :class="{ shimmer: item.status === 'Running' }">
                      {{ item.status }}
                    </span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </DynamicScrollerItem>
      </template>
    </DynamicScroller>
  </div>
</template>
