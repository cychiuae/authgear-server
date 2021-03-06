import React, { useCallback, useContext, useMemo, useState } from "react";
import {
  ActionButton,
  DetailsList,
  IColumn,
  ICommandBarItemProps,
  MessageBar,
  SelectionMode,
  Text,
  VerticalDivider,
} from "@fluentui/react";
import { Context, FormattedMessage } from "@oursky/react-messageformat";
import { Link, useNavigate, useParams } from "react-router-dom";
import produce from "immer";

import ShowError from "../../ShowError";
import ShowLoading from "../../ShowLoading";
import { OAuthClientConfig, PortalAPIAppConfig } from "../../types";
import { copyToClipboard } from "../../util/clipboard";
import { clearEmptyObject } from "../../util/misc";
import { useSystemConfig } from "../../context/SystemConfigContext";
import {
  AppConfigFormModel,
  useAppConfigForm,
} from "../../hook/useAppConfigForm";
import NavBreadcrumb, { BreadcrumbItem } from "../../NavBreadcrumb";
import FormContainer from "../../FormContainer";

import styles from "./OAuthClientConfigurationScreen.module.scss";

interface FormState {
  clients: OAuthClientConfig[];
}

function constructFormState(config: PortalAPIAppConfig): FormState {
  return { clients: config.oauth?.clients ?? [] };
}

function constructConfig(
  config: PortalAPIAppConfig,
  _initialState: FormState,
  currentState: FormState
): PortalAPIAppConfig {
  return produce(config, (config) => {
    config.oauth ??= {};
    config.oauth.clients = currentState.clients;
    clearEmptyObject(config);
  });
}

function makeOAuthClientListColumns(
  renderToString: (messageId: string) => string
): IColumn[] {
  return [
    {
      key: "name",
      fieldName: "name",
      name: renderToString("OAuthClientConfigurationScreen.client-list.name"),
      minWidth: 150,
      className: styles.columnHeader,
    },

    {
      key: "clientId",
      fieldName: "clientId",
      name: renderToString(
        "OAuthClientConfigurationScreen.client-list.client-id"
      ),
      minWidth: 300,
      className: styles.columnHeader,
    },
    { key: "action", name: renderToString("action"), minWidth: 200 },
  ];
}

interface OAuthClientListActionCellProps {
  clientId: string;
  onCopyComplete: () => void;
  onRemoveClientClick: (clientId: string) => void;
}

const OAuthClientListActionCell: React.FC<OAuthClientListActionCellProps> = function OAuthClientListActionCell(
  props: OAuthClientListActionCellProps
) {
  const { clientId, onCopyComplete, onRemoveClientClick } = props;
  const navigate = useNavigate();
  const { themes } = useSystemConfig();

  const onEditClick = useCallback(() => {
    navigate(`./${clientId}/edit`);
  }, [navigate, clientId]);

  const onCopyClick = useCallback(() => {
    copyToClipboard(clientId);

    // Invoke callback
    onCopyComplete();
  }, [clientId, onCopyComplete]);

  const onRemoveClick = useCallback(() => {
    onRemoveClientClick(clientId);
  }, [clientId, onRemoveClientClick]);

  return (
    <div className={styles.cellContent}>
      <ActionButton
        className={styles.cellAction}
        theme={themes.actionButton}
        onClick={onEditClick}
      >
        <FormattedMessage id="edit" />
      </ActionButton>
      <VerticalDivider className={styles.cellActionDivider} />
      <ActionButton
        className={styles.cellAction}
        theme={themes.actionButton}
        onClick={onCopyClick}
      >
        <FormattedMessage id="copy" />
      </ActionButton>
      <VerticalDivider className={styles.cellActionDivider} />
      <ActionButton
        className={styles.cellAction}
        theme={themes.actionButton}
        onClick={onRemoveClick}
      >
        <FormattedMessage id="remove" />
      </ActionButton>
    </div>
  );
};

interface OAuthClientConfigurationContentProps {
  form: AppConfigFormModel<FormState>;
  showNotification: (msg: string) => void;
}

const OAuthClientConfigurationContent: React.FC<OAuthClientConfigurationContentProps> = function OAuthClientConfigurationContent(
  props
) {
  const {
    showNotification,
    form: { state, setState },
  } = props;
  const { renderToString } = useContext(Context);
  const { authgearEndpoint } = useSystemConfig();

  const navBreadcrumbItems: BreadcrumbItem[] = useMemo(() => {
    return [
      {
        to: ".",
        label: <FormattedMessage id="OAuthClientConfigurationScreen.title" />,
      },
    ];
  }, []);

  const oauthClientListColumns = useMemo(() => {
    return makeOAuthClientListColumns(renderToString);
  }, [renderToString]);

  const onClientIdCopied = useCallback(() => {
    showNotification(
      renderToString("OAuthClientConfigurationScreen.client-id-copied")
    );
  }, [showNotification, renderToString]);

  const onRemoveClientClick = useCallback(
    (clientId: string) => {
      setState((state) => ({
        clients: state.clients.filter((c) => c.client_id !== clientId),
      }));
    },
    [setState]
  );

  const onRenderOAuthClientColumns = useCallback(
    (item?: OAuthClientConfig, _index?: number, column?: IColumn) => {
      if (item == null || column == null) {
        return null;
      }
      switch (column.key) {
        case "action":
          return (
            <OAuthClientListActionCell
              clientId={item.client_id}
              onCopyComplete={onClientIdCopied}
              onRemoveClientClick={onRemoveClientClick}
            />
          );
        case "name":
          return <span className={styles.cellContent}>{item.name ?? ""}</span>;
        case "clientId":
          return <span className={styles.cellContent}>{item.client_id}</span>;
        default:
          return null;
      }
    },
    [onClientIdCopied, onRemoveClientClick]
  );

  return (
    <div className={styles.root}>
      <NavBreadcrumb items={navBreadcrumbItems} />
      <section className={styles.clientEndpointSection}>
        <Text className={styles.description}>
          <FormattedMessage
            id="OAuthClientConfigurationScreen.client-endpoint.desc"
            values={{
              clientEndpoint: authgearEndpoint,
              dnsUrl: "../dns/custom-domains",
            }}
            components={{
              Link,
            }}
          />
        </Text>
      </section>
      <DetailsList
        columns={oauthClientListColumns}
        items={state.clients}
        selectionMode={SelectionMode.none}
        onRenderItemColumn={onRenderOAuthClientColumns}
      />
    </div>
  );
};

const OAuthClientConfigurationScreen: React.FC = function OAuthClientConfigurationScreen() {
  const { appID } = useParams();
  const { renderToString } = useContext(Context);
  const navigate = useNavigate();

  const form = useAppConfigForm(appID, constructFormState, constructConfig);

  const [messageBar, setMessageBar] = useState<React.ReactNode>(null);
  const showNotification = useCallback((msg: string) => {
    setMessageBar(
      <MessageBar onDismiss={() => setMessageBar(null)}>
        <p>{msg}</p>
      </MessageBar>
    );
  }, []);

  const commandBarFarItems: ICommandBarItemProps[] = useMemo(
    () => [
      {
        key: "save",
        text: renderToString(
          "OAuthClientConfigurationScreen.add-client-button"
        ),
        iconProps: { iconName: "CirclePlus" },
        onClick: () => navigate("./add"),
      },
    ],
    [navigate, renderToString]
  );

  if (form.isLoading) {
    return <ShowLoading />;
  }

  if (form.loadError) {
    return <ShowError error={form.loadError} onRetry={form.reload} />;
  }

  return (
    <FormContainer
      form={form}
      messageBar={messageBar}
      farItems={commandBarFarItems}
    >
      <OAuthClientConfigurationContent
        form={form}
        showNotification={showNotification}
      />
    </FormContainer>
  );
};

export default OAuthClientConfigurationScreen;
