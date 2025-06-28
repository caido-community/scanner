<script setup lang="ts">
import Card from "primevue/card";
</script>

<template>
  <Card
    class="h-full"
    :pt="{ body: { class: 'h-full' }, content: { class: 'h-full' } }"
  >
    <template #content>
      <div class="flex justify-center items-center h-full">
        <span class="text-red-400"
          >Invalid state. Please report this issue on the Caido Discord
          server.</span
        >
      </div>
    </template>
  </Card>
</template>
