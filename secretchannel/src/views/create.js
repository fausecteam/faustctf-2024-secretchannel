window.onload = () => {
    let forms = document.querySelectorAll(".contentForm");

    const fn = (event) => {
	forms.forEach((value) => {
	    if (value.id !== event.target.value) {
		value.style.display = 'none';
	    } else {
		value.style.display = '';
	    }
	})
    };

    const dropdown = document.querySelector('#type');
    dropdown.onchange = fn;
    fn({target: dropdown})
}
