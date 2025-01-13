# built-in dependencies
from typing import Union, Optional, List
import inspect

# project dependencies
from lightphe.standard_curves import weierstrass, edwards, koblitz

FORM_MODULES = {
    "weierstrass": weierstrass,
    "edwards": edwards,
    "koblitz": koblitz,
}


def list_curves(form_name: str) -> List[str]:
    """
    Lists the supported curves for a given form

    Args:
        form_name (str): curve form name

    Returns:
        List[str]: The list of supported curves
    """

    if FORM_MODULES.get(form_name) is None:
        raise ValueError(f"Unsupported curve form - {form_name}")

    module = FORM_MODULES[form_name]
    module_file = inspect.getsourcefile(module)

    return [
        cls[0].lower().replace("_", "-")
        for cls in inspect.getmembers(module, inspect.isclass)
        if inspect.getsourcefile(cls[1]) == module_file  # exclude imported classes
    ]


def build_curve(form_name: str, curve_name: Optional[str] = None) -> Union[
    "weierstrass.WeierstrassInterface",
    "edwards.TwistedEdwardsInterface",
    "koblitz.KoblitzInterface",
]:
    """
    Builds a curve arguments based on the form and curve name

    Args:
        form_name (str): curve form name
        curve_name (str): curve name

    Returns:
        Union[WeierstrassInterface, TwistedEdwardsInterface, KoblitzInterface]:
            The constructed curve instance

    Raises:
        ValueError: If the form or curve name is unsupported
    """

    curve_map = {
        name: {
            cls[0].lower().replace("_", "-"): cls[0]
            for cls in inspect.getmembers(module, inspect.isclass)
        }
        for name, module in FORM_MODULES.items()
    }

    if form_name not in curve_map:
        raise ValueError(f"Unsupported curve form - {form_name}")

    if curve_name is None:
        module = FORM_MODULES[form_name]
        curve_name = getattr(module, "DEFAULT_CURVE", None)
        if curve_name is None:
            raise ValueError(f"Default curve not defined for {form_name}")

    if curve_name not in curve_map[form_name]:
        raise ValueError(f"Unsupported {form_name} curve - {curve_name}")

    curve_class_name = curve_map[form_name][curve_name]
    module = FORM_MODULES[form_name]
    curve_class = getattr(module, curve_class_name)

    return curve_class()
