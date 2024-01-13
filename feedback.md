| **SLH**              | Labo 2                                      |         |            |                                                              |
| -------------------- | ------------------------------------------- | ------- | ---------- | ------------------------------------------------------------ |
| *Name :*             | vanhove                                     |         |            |                                                              |
| *Grade :*            | 5.54545454545455                            |         |            |                                                              |
|                      |                                             |         |            |                                                              |
| **Objectives**       | **Description**                             | **Max** | **Obtenu** | **Comment**                                                  |
| ***Code\***          |                                             |         |            |                                                              |
|                      | Project implemented and working as expected | 1       | 1          |                                                              |
|                      | Code separation                             | 1       | 1          |                                                              |
|                      | Code quality                                | 2       | 2          |                                                              |
| ***JWT\***           |                                             |         |            |                                                              |
|                      | Create                                      | 2       | 2          |                                                              |
|                      | Verify                                      | 3       | 3          |                                                              |
|                      | Secret                                      | 1       | 1          |                                                              |
|                      | Tests                                       | 1       | 1          |                                                              |
| ***Password/hash\*** |                                             |         |            |                                                              |
|                      | Hash                                        | 1.5     | 1.5        |                                                              |
|                      | Verify                                      | 1       | 0.5        | Overkill verification, just use verify                       |
|                      | Tests                                       | 1       | 1          |                                                              |
| ***Validation\***    |                                             |         |            |                                                              |
|                      | Email                                       | 2       | 1          | Doesn’t check length (-1)                                    |
|                      | Password                                    | 3       | 2          | Miss user input in zxcvbn                                    |
|                      | Tests                                       | 1       | 1          |                                                              |
| ***API\***           |                                             |         |            |                                                              |
|                      | Password change                             | 4       | 4          |                                                              |
|                      | Login                                       | 3       | 2.5        | Leak in message (-0.5)                                       |
|                      | Register                                    | 4       | 3          | Return success with an existing email (-1)                   |
|                      | Verify                                      | 1       | 1          |                                                              |
|                      | Access JWT                                  | 2.5     | 2          | Miss max age of cookie                                       |
| ***Questions\***     |                                             |         |            |                                                              |
|                      | Q1                                          | 3       | 3          |                                                              |
|                      | Q2                                          | 4       | 4          |                                                              |
|                      | Q3                                          | 2       | 1.5        | A local copy is still required (-0.5) you don’t follow the step you mentionned with keeping it only on the server |
| ***Bonus\***         |                                             |         |            |                                                              |
|                      | Any cool feature added                      | +       | 1          | Nice report !                                                |
| ***Malus\***         |                                             |         |            |                                                              |
|                      | Any problem (does not compile, ...)         | -       |            |                                                              |
|                      |                                             |         |            |                                                              |
| **Total**            | 44                                          | 40      |            |                                                              |