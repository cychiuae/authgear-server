import React, { useCallback, useContext, useMemo, useState } from "react";
import {
  DefaultButton,
  Dialog,
  DialogFooter,
  ICommandBarItemProps,
  MessageBar,
  MessageBarType,
  PrimaryButton,
  Text,
} from "@fluentui/react";
import { Context, FormattedMessage } from "@oursky/react-messageformat";
import { useSystemConfig } from "./context/SystemConfigContext";
import NavigationBlockerDialog from "./NavigationBlockerDialog";
import CommandBarContainer from "./CommandBarContainer";
import { APIError } from "./error/error";
import { FormProvider, useFormTopErrors } from "./form";
import { ErrorParseRule, renderError } from "./error/parse";

export interface FormModel {
  updateError: unknown;
  isDirty: boolean;
  isUpdating: boolean;
  reset: () => void;
  save: () => void;
}

const FormErrorMessageBar: React.FC = (props) => {
  const { renderToString } = useContext(Context);

  const errors = useFormTopErrors();
  if (errors.length === 0) {
    return <>{props.children}</>;
  }

  return (
    <MessageBar messageBarType={MessageBarType.error}>
      {errors.map((err, i) => (
        <Text key={i}>{renderError(null, err, renderToString)}</Text>
      ))}
    </MessageBar>
  );
};

export interface SaveButtonProps {
  labelId: string;
  iconName: string;
}

export interface FormContainerProps {
  form: FormModel;
  canSave?: boolean;
  saveButtonProps?: SaveButtonProps;
  localError?: APIError | null;
  errorRules?: ErrorParseRule[];
  fallbackErrorMessageID?: string;
  farItems?: ICommandBarItemProps[];
  messageBar?: React.ReactNode;
}

const FormContainer: React.FC<FormContainerProps> = function FormContainer(
  props
) {
  const { updateError, isDirty, isUpdating, reset, save } = props.form;
  const {
    canSave = true,
    saveButtonProps = { labelId: "save", iconName: "Save" },
    localError,
    errorRules,
    fallbackErrorMessageID,
    farItems,
    messageBar,
  } = props;

  const { themes } = useSystemConfig();
  const { renderToString } = useContext(Context);

  const onFormSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      save();
    },
    [save]
  );

  const [isResetDialogVisible, setIsResetDialogVisible] = useState(false);
  const onDismissResetDialog = useCallback(() => {
    setIsResetDialogVisible(false);
  }, []);
  const doReset = useCallback(() => {
    reset();
    // If the form contains a CodeEditor, dialog dismiss animation does not play.
    // Defer the dismissal to ensure dismiss animation.
    setTimeout(() => setIsResetDialogVisible(false), 0);
  }, [reset]);

  const disabled = isUpdating || !isDirty;
  const commandBarItems: ICommandBarItemProps[] = useMemo(() => {
    return [
      {
        key: "save",
        text: renderToString(saveButtonProps.labelId),
        iconProps: { iconName: saveButtonProps.iconName },
        disabled: disabled || !canSave,
        onClick: () => save(),
      },
      {
        key: "reset",
        text: renderToString("reset"),
        iconProps: { iconName: "Delete" },
        disabled,
        theme: disabled ? themes.main : themes.destructive,
        onClick: () => setIsResetDialogVisible(true),
      },
    ];
  }, [canSave, disabled, save, saveButtonProps, renderToString, themes]);

  const resetDialogContentProps = useMemo(() => {
    return {
      title: <FormattedMessage id="FormContainer.reset-dialog.title" />,
      subText: renderToString("FormContainer.reset-dialog.message"),
    };
  }, [renderToString]);

  return (
    <FormProvider
      error={updateError ?? localError}
      rules={errorRules}
      fallbackErrorMessageID={fallbackErrorMessageID}
    >
      <CommandBarContainer
        isLoading={isUpdating}
        items={commandBarItems}
        farItems={farItems}
        messageBar={<FormErrorMessageBar>{messageBar}</FormErrorMessageBar>}
      >
        <form onSubmit={onFormSubmit}>{props.children}</form>
      </CommandBarContainer>
      <Dialog
        hidden={!isResetDialogVisible}
        dialogContentProps={resetDialogContentProps}
        onDismiss={onDismissResetDialog}
      >
        <DialogFooter>
          <PrimaryButton onClick={doReset} theme={themes.destructive}>
            <FormattedMessage id="reset" />
          </PrimaryButton>
          <DefaultButton onClick={onDismissResetDialog}>
            <FormattedMessage id="cancel" />
          </DefaultButton>
        </DialogFooter>
      </Dialog>
      <NavigationBlockerDialog blockNavigation={isDirty} />
    </FormProvider>
  );
};

export default FormContainer;
