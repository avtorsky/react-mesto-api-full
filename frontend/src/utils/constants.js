export const formInputClass = {
  inputErrorClass: 'form__input_type_error',
  errorClass: 'form__input-error_active'
}

export const validateField = (validator, fieldName) => {
  return Object.keys(validator)
    .map((errorKey) => {
      const errorResult = validator[errorKey](fieldName);
      return { [errorKey]: errorResult };
    })
    .reduce((acc, item) => ({ ...acc, ...item }), {});
};