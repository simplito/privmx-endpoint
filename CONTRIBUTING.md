# Contributing to PrivMX

## Welcome Contributors! 🎉

Thank you for your interest in contributing to our project. This document provides guidelines and instructions for contributing.

## Legal Notice

If you want to contribute to the project, you can clone the repository, make changes, and then submit a Pull Request (follow the guidelines below).
Submitting Pull Requests to SIMPLITO's repositories is the only way of publishing modifications made to our code allowed by our License.
**All the code contributed to the project is under full commercial ownership of SIMPLITO.**

- [Licensing information](https://privmx.dev/licensing)
- [Contact us](https://privmx.com/en/contact-us) in case of further questions.

## How Can You Contribute?

### Reporting Bugs 🐛

1. **Check Existing Issues**, before submitting a bug report.
2. **Provide Detailed Information**, according to the bug report template in each project.

### Feature Requests 💡

1. **Check Existing Suggestions**: Verify that your feature hasn't been suggested before.
2. **Open a Clear Issue**, describing it according to the feature request template in each project.
3. (Optional) **Open a discussion**, if you want to discuss or make sure that the feature is actually necessary.

### Coding Guidelines 💻

- Follow the project's coding style and conventions
- Write clear, concise, and well-documented code
- Include comments for complex logic

### Commit Message Conventions

- Use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/)
- Reference issue numbers when applicable

### Pull Request Process

1. **Prepare Your Changes**

   - Ensure code follows project guidelines
   - Add/update tests as needed
   - Update documentation in code

2. **Submit Pull Request**

   - Title should be clear and descriptive
   - Include a detailed description of changes
   - Link any related issues

3. **Code Review**
   - Maintainers will review your PR
   - Be open to feedback and suggested changes
   - Discussions and iterations are part of the process

## Semantic Versioning Rules (A.B.C-rcX)

- **New Features**: Increment `A` (major) for major changes or incompatible features, `B` (minor) for minor changes (mostly compatible with previous versions).
- **Consistency**: Main library and wrappers use the same `A` and `B` versioning.
- **Updates**: `C` changes are fixes and updates without new features; `C` doesn't need to be synchronized between library and wrappers.
- **Release Candidate (rc)**: `X` represents consecutive release candidates for a given version.
- **Before Official Release**: Release as `A.B.C-rcX` before final release; changes to new API are possible and update `X`.
- **Finalizing a Version**: Release stable version when library and wrappers are fully compatible.
- **Minor Changes (B)**: Increment `B` for small features, replace older functionality, and mark deprecated functions.
- **Major Changes (A)**: Increment `A` for introducing major changes or features.

Read more about versioning in PrivMX in [our docs](https://docs.privmx.dev/start/versioning/).

## Additional Resources

- [PrivMX Documentation](https://docs.privmx.dev/)
- [Project map](https://docs.privmx.dev/start/project-map)

## Questions?

If you have any questions, please:

- Check the documentation
- Open an issue or a discussion in the appropriate repository

---

**Thank you for contributing!** 🚀
