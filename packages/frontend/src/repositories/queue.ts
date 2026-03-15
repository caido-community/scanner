import { useSDK } from "@/plugins/sdk";

export const useQueueRepository = () => {
  const sdk = useSDK();

  const getQueueTasks = async () => {
    const response = await sdk.backend.getQueueTasks();
    return response;
  };

  const getQueueTask = async (id: string) => {
    const response = await sdk.backend.getQueueTask(id);
    return response;
  };

  const getRequestResponse = async (requestId: string) => {
    const response = await sdk.backend.getRequestResponse(requestId);
    return response;
  };

  const clearQueueTasks = async () => {
    const response = await sdk.backend.clearQueueTasks();
    return response;
  };

  return {
    getQueueTasks,
    getQueueTask,
    getRequestResponse,
    clearQueueTasks,
  };
};
