from django import forms
import os
from pathlib import Path
from hyprfire.settings import BASE_DIR

WINDOW_SIZES = [
    (1000, '1000'),
    (2000, '2000'),
]

ALGORITHMS = [
    ('Benford', 'Benford'),
    ('Zipf', 'Zipf'),
]

ANALYSIS = [
    ('Length', 'Length'),
    ('Time', 'Time'),
]


class AnalyseForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['filenames'] = forms.FilePathField(label='Files', path=self.path, recursive=False, allow_files=True)

    path = str(Path(BASE_DIR) / 'pcaps')
    window = forms.CharField(label="Window Size ", widget=forms.Select(choices=WINDOW_SIZES))
    algorithm = forms.CharField(label="Algorithm ", widget=forms.Select(choices=ALGORITHMS))
    analysis = forms.CharField(label="Analysis ", widget=forms.Select(choices=ANALYSIS))
