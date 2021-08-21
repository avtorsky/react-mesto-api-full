import { useState, useCallback } from 'react';

export function useFormValidation() {
  const [values, setValues] = useState({});
  const [errors, setErrors] = useState({});
  const [isValid, setIsValid] = useState(true);

  const handleChange = (elem) => {
    const {name, value} = elem.target;
    setValues({ ...values, [name]: value });
    setErrors({ ...errors, [name]: elem.target.validationMessage });
    setIsValid(elem.target.closest("form").checkValidity());
  };

  const resetForm = useCallback((newValues = {}, newErrors = {}, newIsValid = false) => {
    setValues(newValues);
    setErrors(newErrors);
    setIsValid(newIsValid)
  }, [setValues, setErrors, setIsValid]);

  return { values, handleChange, errors, isValid, resetForm };
}