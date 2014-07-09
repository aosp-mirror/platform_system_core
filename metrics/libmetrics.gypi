{
  'target_defaults': {
    'variables': {
      'deps': [
        'libchrome-<(libbase_ver)',
        'libchromeos-<(libbase_ver)',
      ]
    },
    'cflags_cc': [
      '-fno-exceptions',
    ],
  },
  'targets': [
    {
      'target_name': 'libmetrics-<(libbase_ver)',
      'type': 'shared_library',
      'cflags': [
        '-fvisibility=default',
      ],
      'libraries+': [
        '-lpolicy-<(libbase_ver)',
      ],
      'sources': [
        'c_metrics_library.cc',
        'metrics_library.cc',
        'timer.cc',
        'components/metrics/chromeos/metric_sample.cc',
        'components/metrics/chromeos/serialization_utils.cc',
      ],
      'include_dirs': ['.'],
    },
  ],
}
