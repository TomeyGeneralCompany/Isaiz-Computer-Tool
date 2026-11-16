          const endpoint=process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat";
          const request={ model, stream: false, think: profile.think, messages:requestMessages,
          ...(structured ? {format:requestSchema} : {tools:availableTools}),
          keep_alive:"30m",
          options: { num_predict:turnGenerationLimit,
            ...(limits.numCtx === undefined ? {} : {num_ctx:settings.numCtx}),
            ...(limits.numThreads === undefined ? {} : {num_thread:settings.numThreads}), ...profile.options } };
