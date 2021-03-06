import React from "react";
import { gql } from "@apollo/client";
import yaml from "js-yaml";

import { useGraphqlMutation } from "../../../hook/graphql";
import { client } from "../../portal/apollo";
import { PortalAPIApp, PortalAPIAppConfig } from "../../../types";
import {
  UpdateAppConfigMutation,
  UpdateAppConfigMutationVariables,
} from "./__generated__/UpdateAppConfigMutation";

const APP_CONFIG_PATH = "authgear.yaml";

const updateAppConfigMutation = gql`
  mutation UpdateAppConfigMutation(
    $appID: ID!
    $updates: [AppResourceUpdate!]!
  ) {
    updateAppResources(input: { appID: $appID, updates: $updates }) {
      app {
        id
        rawAppConfig
        effectiveAppConfig
      }
    }
  }
`;

export function useUpdateAppConfigMutation(
  appID: string
): {
  updateAppConfig: (
    appConfig: PortalAPIAppConfig
  ) => Promise<PortalAPIApp | null>;
  loading: boolean;
  error: unknown;
  resetError: () => void;
} {
  const [mutationFunction, { error, loading }, resetError] = useGraphqlMutation<
    UpdateAppConfigMutation,
    UpdateAppConfigMutationVariables
  >(updateAppConfigMutation, { client });
  const updateAppConfig = React.useCallback(
    async (appConfig: PortalAPIAppConfig) => {
      const appConfigYaml = yaml.safeDump(appConfig);

      const result = await mutationFunction({
        variables: {
          appID,
          updates: [{ path: APP_CONFIG_PATH, data: btoa(appConfigYaml) }],
        },
      });
      return result.data?.updateAppResources.app ?? null;
    },
    [appID, mutationFunction]
  );
  return { updateAppConfig, error, loading, resetError };
}
