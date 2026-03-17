<script setup lang="ts">
import { type EditorView } from "@codemirror/view";
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

import { useSDK } from "@/plugins/sdk";

const { raw } = defineProps<{
  raw: string;
}>();

const sdk = useSDK();
const root = ref<HTMLElement>();
const editorView = ref<EditorView>();

const updateEditorContent = (content: string) => {
  if (editorView.value === undefined) {
    return;
  }

  editorView.value.dispatch({
    changes: {
      from: 0,
      to: editorView.value.state.doc.length,
      insert: content,
    },
  });
};

const initializeEditor = () => {
  if (root.value === undefined || editorView.value !== undefined) {
    return;
  }

  const editor = sdk.ui.httpRequestEditor();
  root.value.appendChild(editor.getElement());
  editorView.value = editor.getEditorView();
  updateEditorContent(raw);
};

onMounted(() => {
  initializeEditor();
});

watch(
  () => raw,
  (newRaw) => {
    updateEditorContent(newRaw);
  },
);

onBeforeUnmount(() => {
  editorView.value = undefined;
  Array.from(root.value?.children ?? []).forEach((child) => {
    child.remove();
  });
});
</script>

<template>
  <div ref="root" class="h-full min-h-0 overflow-hidden"></div>
</template>
